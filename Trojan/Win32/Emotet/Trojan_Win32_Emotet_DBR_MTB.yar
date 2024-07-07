
rule Trojan_Win32_Emotet_DBR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_00_0 = {46 00 47 00 44 00 53 00 46 00 67 00 73 00 64 00 66 00 73 00 67 00 64 00 43 00 44 00 44 00 53 00 41 00 53 00 41 00 53 00 53 00 } //10 FGDSFgsdfsgdCDDSASASS
		$a_00_1 = {56 00 41 00 4e 00 43 00 59 00 4b 00 4c 00 28 00 } //10 VANCYKL(
		$a_81_2 = {43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 41 } //1 CryptAcquireContextA
		$a_81_3 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
		$a_81_4 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1 FindResourceA
		$a_81_5 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //1 LockResource
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=24
 
}