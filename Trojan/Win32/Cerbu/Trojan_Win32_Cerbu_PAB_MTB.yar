
rule Trojan_Win32_Cerbu_PAB_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 ff 30 64 89 20 e8 ?? ?? ?? ?? 8d 45 fc 50 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 } //3
		$a_01_1 = {62 70 63 67 79 75 66 72 } //2 bpcgyufr
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}