
rule Trojan_Win64_NjRat_NEBG_MTB{
	meta:
		description = "Trojan:Win64/NjRat.NEBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 41 96 30 44 0c 90 01 01 48 ff c1 48 83 f9 90 01 01 72 f0 c6 90 00 } //10
		$a_01_1 = {37 31 2e 44 4c 4c } //1 71.DLL
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}