
rule Trojan_Win64_Lazy_GTK_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {b6 5e ff 73 69 02 63 31 88 3f a5 2c e4 53 32 1f 80 15 ?? ?? ?? ?? 30 cd 46 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}