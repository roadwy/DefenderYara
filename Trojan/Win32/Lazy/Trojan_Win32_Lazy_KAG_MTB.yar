
rule Trojan_Win32_Lazy_KAG_MTB{
	meta:
		description = "Trojan:Win32/Lazy.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {45 6e 67 6d 54 35 31 37 37 74 31 2e 44 6c 4c } //EngmT5177t1.DlL  1
		$a_80_1 = {6b 57 6f 76 65 72 2c 68 61 64 73 65 61 } //kWover,hadsea  1
		$a_80_2 = {4d 4c 62 65 61 73 74 6c } //MLbeastl  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}