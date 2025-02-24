
rule Trojan_Win32_Nivdort_ND_MTB{
	meta:
		description = "Trojan:Win32/Nivdort.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c8 ff e9 c8 0a ?? ?? f6 46 0c 40 75 ?? 56 e8 55 0c ?? ?? 59 ba 28 67 ?? ?? 83 f8 ff 74 } //3
		$a_03_1 = {c1 e1 06 03 0c b5 60 84 42 00 eb ?? 8b ca f6 41 24 7f } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}