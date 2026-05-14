
rule Trojan_Win64_Rozena_MKB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 0f b6 00 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 08 8b 45 f8 48 63 d0 48 8b 45 10 48 01 d0 44 89 c2 31 ca 88 10 83 45 fc 01 83 45 f8 01 } //25
		$a_01_1 = {6d 79 73 75 70 65 72 73 65 63 72 65 74 6b 65 79 } //10 mysupersecretkey
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*10) >=35
 
}