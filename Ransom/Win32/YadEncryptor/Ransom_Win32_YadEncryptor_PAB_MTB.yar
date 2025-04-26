
rule Ransom_Win32_YadEncryptor_PAB_MTB{
	meta:
		description = "Ransom:Win32/YadEncryptor.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 69 61 20 70 72 69 76 61 74 61 20 61 20 66 6f 73 74 20 64 69 73 74 72 75 73 61 2e 20 59 41 44 20 41 20 49 4e 56 49 4e 53 2e } //1 Cheia privata a fost distrusa. YAD A INVINS.
		$a_81_1 = {40 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 @\\.\PhysicalDrive0
		$a_01_2 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //1 GetDiskFreeSpaceExA
		$a_01_3 = {59 41 44 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 YAD Ransomware
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}