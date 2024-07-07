
rule Trojan_Win32_Kraptik_gen_B{
	meta:
		description = "Trojan:Win32/Kraptik.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 c6 8c 99 07 bb 56 33 db 52 53 ff 15 90 01 02 40 00 90 00 } //1
		$a_02_1 = {6a 05 21 d9 8b d1 bf 3d 46 04 00 57 ff 15 90 01 02 40 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}