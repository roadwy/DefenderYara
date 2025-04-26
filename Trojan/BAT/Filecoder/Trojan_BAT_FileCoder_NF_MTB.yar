
rule Trojan_BAT_FileCoder_NF_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 03 17 28 ?? 00 00 06 02 02 04 28 ?? 00 00 06 16 28 ?? 00 00 06 28 ?? 00 00 06 16 28 ?? 00 00 06 0b } //5
		$a_01_1 = {4f 6e 79 78 4c 6f 63 6b 65 72 } //1 OnyxLocker
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_FileCoder_NF_MTB_2{
	meta:
		description = "Trojan:BAT/FileCoder.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 61 6d 69 74 79 4c 6f 63 6b 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 6d 65 73 73 61 67 65 72 6f 67 75 65 2e 74 78 74 } //2 CalamityLocker.Resources.messagerogue.txt
		$a_01_1 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 20 62 79 20 74 68 65 20 52 6f 67 75 65 42 79 74 65 20 72 61 6e 73 6f 6d 77 61 72 65 } //1 Your system has been compromised by the RogueByte ransomware
		$a_01_2 = {49 6e 20 6f 72 64 65 72 20 74 6f 20 72 65 67 61 69 6e 20 61 63 63 65 73 73 20 74 6f 20 79 6f 75 72 20 73 79 73 74 65 6d 20 61 6e 64 20 66 69 6c 65 73 2c 20 79 6f 75 20 6d 75 73 74 20 73 65 6e 64 20 75 73 20 31 30 30 24 } //1 In order to regain access to your system and files, you must send us 100$
		$a_01_3 = {45 76 65 72 79 20 31 30 20 6d 69 6e 75 74 65 73 20 61 20 72 61 6e 64 6f 6d 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 20 69 6e 20 79 6f 75 72 20 73 79 73 74 65 6d 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 } //1 Every 10 minutes a random encrypted file in your system will be deleted
		$a_01_4 = {49 66 20 79 6f 75 20 66 61 69 6c 20 74 6f 20 70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 77 69 74 68 69 6e 20 32 34 20 68 6f 75 72 73 2c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //1 If you fail to pay the ransom within 24 hours, your files will be lost
		$a_01_5 = {4d 6f 6e 65 72 6f 20 63 61 6e 20 62 65 20 62 6f 75 67 68 74 20 66 72 6f 6d 20 67 65 74 6d 6f 6e 65 72 6f } //1 Monero can be bought from getmonero
		$a_01_6 = {42 79 20 63 6c 6f 73 69 6e 67 20 74 68 69 73 20 77 69 6e 64 6f 77 20 79 6f 75 20 77 69 6c 6c 20 6c 6f 73 65 20 74 68 65 20 70 6f 73 73 69 62 69 6c 69 74 79 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 By closing this window you will lose the possibility to decrypt your files
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}