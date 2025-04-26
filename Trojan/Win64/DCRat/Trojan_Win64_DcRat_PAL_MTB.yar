
rule Trojan_Win64_DcRat_PAL_MTB{
	meta:
		description = "Trojan:Win64/DcRat.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4b 45 52 4e 4c 8b e9 c7 85 ?? ?? ?? ?? 45 4c 33 32 8b cb c7 85 ?? ?? ?? ?? 2e 44 4c } //2
		$a_01_1 = {80 30 11 48 8d 40 01 ff c1 83 f9 0c } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}