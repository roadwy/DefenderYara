
rule Ransom_MSIL_Cryptolocker_EI_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 0b 00 00 32 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //32 00  Ransomware.exe
		$a_81_1 = {53 74 75 62 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //14 00  Stub.Properties.Resources
		$a_81_2 = {48 65 6c 6c 6f 20 69 6d 20 63 72 79 70 74 69 6e 67 20 79 6f 75 72 20 66 69 6c 65 73 20 72 69 67 68 74 20 6e 6f 77 } //14 00  Hello im crypting your files right now
		$a_81_3 = {42 6c 6f 77 66 69 73 68 4d 61 6e 61 67 65 64 } //14 00  BlowfishManaged
		$a_81_4 = {56 69 72 74 75 61 6c 42 6f 78 20 64 65 74 65 63 74 65 64 } //03 00  VirtualBox detected
		$a_81_5 = {2e 44 45 44 53 45 43 } //03 00  .DEDSEC
		$a_81_6 = {2e 64 65 61 64 73 65 63 75 72 65 } //03 00  .deadsecure
		$a_81_7 = {57 4d 49 43 20 42 49 4f 53 20 47 45 54 20 53 45 52 49 41 4c 4e 55 4d 42 45 52 } //01 00  WMIC BIOS GET SERIALNUMBER
		$a_81_8 = {41 45 53 45 6e 63 72 79 70 74 } //01 00  AESEncrypt
		$a_81_9 = {45 6e 63 72 79 70 74 } //01 00  Encrypt
		$a_81_10 = {47 65 74 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //00 00  GetRandomFileName
	condition:
		any of ($a_*)
 
}