
rule Trojan_Win32_Dtasioa_A{
	meta:
		description = "Trojan:Win32/Dtasioa.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 6d 00 00 04 06 7e 6d 00 00 04 06 91 06 61 20 aa 00 00 00 61 d2 9c 06 17 58 0a } //01 00 
		$a_01_1 = {31 45 39 38 46 46 43 36 2d 37 35 43 37 2d 34 42 32 34 2d 42 36 36 31 2d 35 35 33 33 34 32 33 35 32 42 38 42 } //01 00  1E98FFC6-75C7-4B24-B661-553342352B8B
		$a_01_2 = {45 31 30 35 46 34 45 34 2d 30 46 34 39 2d 34 38 31 39 2d 38 42 39 43 2d 38 33 37 32 37 33 45 34 39 34 39 46 } //01 00  E105F4E4-0F49-4819-8B9C-837273E4949F
		$a_01_3 = {70 61 70 65 72 2d 77 61 6c 6c 65 74 2d 2a 2e 70 6e 67 } //01 00  paper-wallet-*.png
		$a_01_4 = {53 63 72 65 65 6e 73 68 6f 74 20 66 61 69 6c 65 64 } //01 00  Screenshot failed
		$a_01_5 = {46 61 69 6c 65 64 20 70 61 72 73 69 6e 67 20 63 66 67 } //01 00  Failed parsing cfg
		$a_01_6 = {53 65 63 6f 6e 64 20 73 74 61 67 65 20 73 69 7a 65 3a 20 7b 30 7d } //01 00  Second stage size: {0}
		$a_01_7 = {4a 61 78 78 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 77 61 6c 6c 65 74 2e 64 61 74 } //01 00  Jaxx\Local Storage\wallet.dat
		$a_01_8 = {70 65 65 72 50 75 62 6c 69 63 4b 65 79 20 6d 75 73 74 20 62 65 20 6e 75 6c 6c 20 6f 72 20 33 32 20 62 79 74 65 73 20 6c 6f 6e 67 } //00 00  peerPublicKey must be null or 32 bytes long
	condition:
		any of ($a_*)
 
}