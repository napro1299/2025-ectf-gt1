# wolfSSL MPLAB X Project Files for XC16

This directory contains project files for the Microchip MPLAB X IDE. These
projects have been set up to use the Microchip PIC24 Starter Kit
and the Microchip XC16 compiler.

In order to generate the necessary auto-generated MPLAB X files, make sure
to import the wolfssl.X project into your MPLAB X workspace before trying to
build the wolfCrypt test. This will correctly set up the respective project's
Makefiles.

## Included Project Files

### wolfSSL library (wolfssl.X)

This project builds a static wolfSSL library. The settings for this project are in `user_settings.h`:
```
<wolfssl_root>/IDE/MPLABX16/user_settings.h
```

After this project has been built, the compiled library will be located at:
```
<wolfssl_root>/IDE/MPLABX16/wolfssl.X/dist/default/production/wolfssl.X.a
```

### wolfCrypt Test App (wolfcrypt_test.X)

This project tests the wolfCrypt cryptography modules. It is generally a good
idea to run this first on an embedded system after compiling wolfSSL in order
to verify all underlying crypto is working correctly. This project depends on
files generated by Microchip's MCC tool to view the UART output. Follow the
steps below to generate that code.

## Generating MCC UART code

1. Open the MPLAB Code Configurator application.

2. Set the Project path to the wolfSSL/IDE/MPLABX16 and enter your PIC device
into the interface.

3. Select MCC Classic as the content type and click `Finish`.

4. Under the Device Resources section, find the UART entry and add the UART1
peripheral.

5. Note the UART settings and check the `Enable UART Interrupts` and
`Redirect Printf to UART` boxes.

6. Click the `Generate` button.


**Note** : If using an older version of `xc16`, you may have to add the
following to `user_settings.h`.
```
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX
```

## Support

Please send questions or comments to support@wolfssl.com

