
rule Trojan_Win64_LummaStealer_GVL_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 01 30 d0 88 44 24 27 44 89 cd } //3
		$a_02_1 = {48 63 45 24 42 80 34 30 35 8b 45 24 83 c0 01 89 45 1c 8b 05 ?? ?? ?? ?? 8d 48 ?? 0f af c8 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_02_1  & 1)*3) >=3
 
}