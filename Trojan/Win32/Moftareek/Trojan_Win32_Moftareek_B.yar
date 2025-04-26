
rule Trojan_Win32_Moftareek_B{
	meta:
		description = "Trojan:Win32/Moftareek.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 64 65 76 5c 77 69 7a 61 72 64 5f 73 70 69 64 65 72 5c 52 65 73 6f 75 72 63 65 73 5c 45 6d 6f 74 65 74 5c 45 6d 6f 74 65 74 43 6c 69 65 6e 74 44 4c 4c 5c 52 65 6c 65 61 73 65 5c 45 6d 6f 74 65 74 43 6c 69 65 6e 74 44 4c 4c 2e 70 64 62 } //1 \Documents\dev\wizard_spider\Resources\Emotet\EmotetClientDLL\Release\EmotetClientDLL.pdb
		$a_01_1 = {65 78 65 63 75 74 65 4c 61 74 4d 6f 76 65 6d 65 6e 74 43 6d 64 40 40 59 41 5f 4e 50 41 56 45 6d 6f 74 65 74 43 6f 6d 6d 73 40 40 } //1 executeLatMovementCmd@@YA_NPAVEmotetComms@@
		$a_01_2 = {73 65 6e 64 52 65 71 75 65 73 74 40 45 6d 6f 74 65 74 43 6f 6d 6d 73 40 40 } //1 sendRequest@EmotetComms@@
		$a_01_3 = {73 75 63 63 65 73 73 66 75 6c 6c 79 20 73 65 74 20 74 61 73 6b 20 6f 75 74 70 75 74 } //1 successfully set task output
		$a_01_4 = {5c 59 67 79 68 6c 71 74 5c 42 78 35 6a 66 6d 6f 5c 52 34 33 48 2e 64 6c 6c } //1 \Ygyhlqt\Bx5jfmo\R43H.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}