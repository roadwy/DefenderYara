
rule Trojan_Win32_Ursnif_KA{
	meta:
		description = "Trojan:Win32/Ursnif.KA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 3a 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 47 29 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 55 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 41 29 00 } //1
		$a_01_1 = {8b 08 69 c9 0d 66 19 00 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}