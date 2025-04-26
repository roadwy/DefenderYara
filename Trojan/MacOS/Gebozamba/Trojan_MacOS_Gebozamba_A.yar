
rule Trojan_MacOS_Gebozamba_A{
	meta:
		description = "Trojan:MacOS/Gebozamba.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c2 c1 fa 1f c1 ea 1c 01 c2 83 e2 f0 89 c6 29 d6 8a 14 0e 30 94 05 ?? ?? ?? ?? 48 ff c0 48 83 f8 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}