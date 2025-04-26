
rule Trojan_Win32_Zusy_RZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 85 64 f4 ff ff 8a 08 88 8d 77 f4 ff ff 8b 95 68 f4 ff ff 8a 85 77 f4 ff ff 88 02 8b 8d 64 f4 ff ff 83 c1 01 } //1
		$a_01_1 = {70 69 70 65 5c 76 53 44 73 47 52 46 73 36 32 67 68 66 } //1 pipe\vSDsGRFs62ghf
		$a_01_2 = {70 69 70 65 5c 76 73 56 53 44 44 54 47 48 47 53 79 35 34 } //1 pipe\vsVSDDTGHGSy54
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}