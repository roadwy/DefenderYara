
rule Ransom_MSIL_Kraken{
	meta:
		description = "Ransom:MSIL/Kraken,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0c 00 00 04 00 "
		
	strings :
		$a_01_0 = {44 65 61 72 20 25 31 21 5c 72 5c 6e 41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 73 75 63 68 20 61 73 20 64 6f 63 75 6d 65 6e 74 73 2c 20 69 6d 61 67 65 73 2c 20 76 69 64 65 6f 73 20 61 6e 64 20 6f 74 68 65 72 20 66 69 6c 65 73 5c 72 5c 6e 77 69 74 68 20 74 68 65 20 64 69 66 66 65 72 65 6e 74 20 6e 61 6d 65 73 20 61 6e 64 20 65 78 74 65 6e 73 69 6f 6e 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2e } //04 00  Dear %1!\r\nAll of your files such as documents, images, videos and other files\r\nwith the different names and extensions are encrypted.
		$a_01_1 = {52 65 61 64 20 74 68 65 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 20 66 69 6c 65 20 6e 61 6d 65 64 20 5c 22 25 32 5c 22 20 66 6f 72 20 6d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e } //04 00  Read the instructions file named \"%2\" for more information.
		$a_01_2 = {59 6f 75 20 63 61 6e 20 66 69 6e 64 20 74 68 69 73 20 66 69 6c 65 20 65 76 65 72 79 77 68 65 72 65 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 2e } //04 00  You can find this file everywhere on your computer.
		$a_01_3 = {2a 20 44 6f 6e 27 74 20 44 65 6c 65 74 65 20 45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 5c 72 5c 6e 2a 20 44 6f 6e 27 74 20 4d 6f 64 69 66 79 20 45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 5c 72 5c 6e 2a 20 44 6f 6e 27 74 20 52 65 6e 61 6d 65 20 45 6e 63 72 79 70 74 65 64 20 46 69 6c 65 73 } //06 00  * Don't Delete Encrypted Files\r\n* Don't Modify Encrypted Files\r\n* Don't Rename Encrypted Files
		$a_01_4 = {22 6e 61 6d 65 22 3a 20 22 4b 72 61 6b 65 6e 20 43 72 79 70 74 6f 72 22 } //06 00  "name": "Kraken Cryptor"
		$a_01_5 = {22 63 6f 6d 6d 65 6e 74 22 3a 20 22 52 65 73 65 61 72 63 68 65 72 73 20 45 64 69 74 6f 6e 3a 20 5a 65 72 6f 20 52 65 73 69 73 74 61 6e 63 65 22 } //06 00  "comment": "Researchers Editon: Zero Resistance"
		$a_01_6 = {22 73 75 70 70 6f 72 74 5f 65 6d 61 69 6c 22 3a 20 22 6e 69 6b 6f 6c 61 74 65 73 6c 61 40 63 6f 63 6b 2e 6c 69 22 } //06 00  "support_email": "nikolatesla@cock.li"
		$a_01_7 = {22 73 75 70 70 6f 72 74 5f 65 6d 61 69 6c 22 3a 20 22 6f 6e 69 6f 6e 68 65 6c 70 40 6d 65 6d 65 77 61 72 65 2e 6e 65 74 22 } //06 00  "support_email": "onionhelp@memeware.net"
		$a_01_8 = {22 73 75 70 70 6f 72 74 5f 61 6c 74 65 72 6e 61 74 69 76 65 61 22 3a 20 22 6e 69 6b 6f 6c 61 74 65 73 6c 61 70 72 6f 74 6f 6e 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d 22 } //06 00  "support_alternativea": "nikolateslaproton@protonmail.com"
		$a_01_9 = {22 73 75 70 70 6f 72 74 5f 61 6c 74 65 72 6e 61 74 69 76 65 61 22 3a 20 22 42 4d 2d 32 63 57 64 68 6e 34 66 35 55 79 4d 76 72 75 44 42 47 73 35 62 4b 37 37 4e 73 43 46 41 4c 4d 4a 6b 52 40 62 69 74 6d 65 73 73 61 67 65 2e 63 68 22 } //02 00  "support_alternativea": "BM-2cWdhn4f5UyMvruDBGs5bK77NsCFALMJkR@bitmessage.ch"
		$a_01_10 = {22 70 72 69 63 65 5f 75 6e 69 74 22 3a 20 22 42 54 43 22 } //02 00  "price_unit": "BTC"
		$a_01_11 = {22 74 61 72 67 65 74 5f 65 78 74 65 6e 73 69 6f 6e 73 22 3a 20 5b } //00 00  "target_extensions": [
		$a_00_12 = {78 0c 03 00 7e 00 7e 00 0e 00 00 0a 00 0a 01 4b } //72 61 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Kraken_2{
	meta:
		description = "Ransom:MSIL/Kraken,SIGNATURE_TYPE_PEHSTR_EXT,7e 00 7e 00 0e 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4b 72 61 6b 65 6e 2e 65 78 65 } //0a 00  Kraken.exe
		$a_00_1 = {6b 72 61 6b 65 6e 20 43 72 79 70 74 6f 72 } //0a 00  kraken Cryptor
		$a_01_2 = {4b 52 41 4b 45 4e 20 45 4e 43 52 59 50 54 20 55 4e 49 51 55 45 20 4b 45 59 } //01 00  KRAKEN ENCRYPT UNIQUE KEY
		$a_01_3 = {48 6f 77 20 63 61 6e 20 72 65 63 6f 76 65 72 79 20 6d 79 20 66 69 6c 65 73 3f } //01 00  How can recovery my files?
		$a_01_4 = {57 65 20 67 75 61 72 61 6e 74 65 65 20 74 68 61 74 20 79 6f 75 20 63 61 6e 20 72 65 63 6f 76 65 72 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 73 6f 6f 6e 20 73 61 66 65 6c 79 2e } //01 00  We guarantee that you can recover all your files soon safely.
		$a_01_5 = {59 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 65 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 73 6d 61 6c 6c 65 72 20 66 69 6c 65 20 66 6f 72 20 66 72 65 65 20 69 6e 20 74 68 65 20 66 69 72 73 74 20 63 6f 6e 74 61 63 74 20 77 69 74 68 20 75 73 2e } //01 00  You can decrypt one of your encrypted smaller file for free in the first contact with us.
		$a_01_6 = {41 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 63 72 79 70 74 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 3f 20 49 66 20 79 65 73 21 20 59 6f 75 20 6e 65 65 64 20 74 6f 20 70 61 79 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 73 65 72 76 69 63 65 20 74 6f 20 75 73 21 } //01 00  Are you want to decrypt all of your encrypted files? If yes! You need to pay for decryption service to us!
		$a_01_7 = {41 66 74 65 72 20 79 6f 75 72 20 70 61 79 6d 65 6e 74 20 6d 61 64 65 2c 20 61 6c 6c 20 6f 66 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 64 65 63 72 79 70 74 65 64 2e } //01 00  After your payment made, all of your encrypted files has been decrypted.
		$a_01_8 = {48 6f 77 20 6d 75 63 68 20 69 73 20 6e 65 65 64 20 74 6f 20 70 61 79 3f } //01 00  How much is need to pay?
		$a_01_9 = {54 68 69 73 20 70 72 69 63 65 20 69 73 20 66 6f 72 20 74 68 65 20 63 6f 6e 74 61 63 74 20 77 69 74 68 20 75 73 20 69 6e 20 66 69 72 73 74 20 77 65 65 6b 20 6f 74 68 65 72 77 69 73 65 20 69 74 20 77 69 6c 6c 20 69 6e 63 72 65 61 73 65 2e } //01 00  This price is for the contact with us in first week otherwise it will increase.
		$a_01_10 = {44 4f 4e 27 54 20 4d 4f 44 49 46 59 20 4f 52 20 52 45 4e 41 4d 45 20 45 4e 43 52 59 50 54 45 44 20 46 49 4c 45 53 21 } //01 00  DON'T MODIFY OR RENAME ENCRYPTED FILES!
		$a_01_11 = {44 4f 4e 27 54 20 55 53 45 20 54 48 49 52 44 20 50 41 52 54 59 2c 20 50 55 42 4c 49 43 20 54 4f 4f 4c 53 2f 53 4f 46 54 57 41 52 45 20 54 4f 20 44 45 43 52 59 50 54 20 59 4f 55 52 20 46 49 4c 45 53 2c 20 54 48 49 53 20 43 41 55 53 45 20 44 41 4d 41 47 45 20 59 4f 55 52 20 46 49 4c 45 53 20 50 45 52 4d 41 4e 45 4e 54 4c 59 21 } //01 00  DON'T USE THIRD PARTY, PUBLIC TOOLS/SOFTWARE TO DECRYPT YOUR FILES, THIS CAUSE DAMAGE YOUR FILES PERMANENTLY!
		$a_01_12 = {4e 4f 20 50 41 59 4d 45 4e 54 2c 20 4e 4f 20 44 45 43 52 59 50 54 } //64 00  NO PAYMENT, NO DECRYPT
		$a_81_13 = {35 33 30 64 65 37 64 35 2d 65 62 34 35 2d 34 63 61 33 2d 61 66 61 61 2d 32 35 35 64 63 35 63 33 34 38 39 63 } //00 00  530de7d5-eb45-4ca3-afaa-255dc5c3489c
		$a_00_14 = {5d 04 00 00 f4 c0 03 80 5c 3d 00 00 f5 c0 03 80 00 00 01 00 04 00 27 00 54 72 6f 6a 61 6e 44 6f 77 6e 6c 6f 61 64 65 72 3a 53 63 72 69 70 74 2f 41 48 43 6f 69 6e 4d 69 6e 65 72 2e 67 65 6e 00 00 01 40 05 82 5c 00 04 00 e7 66 00 00 00 00 62 00 0f 0b ac ce bc 3f d7 ac 1a 3f ea ac bc 13 80 0b ec c7 31 0b f2 e6 1e 78 e3 a3 05 ac f2 3f ad f2 3f } //80 0b 
	condition:
		any of ($a_*)
 
}