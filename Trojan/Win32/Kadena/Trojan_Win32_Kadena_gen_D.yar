
rule Trojan_Win32_Kadena_gen_D{
	meta:
		description = "Trojan:Win32/Kadena.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {37 48 45 76 ?? 74 47 73 74 ?? 72 72 6f 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=3
 
}