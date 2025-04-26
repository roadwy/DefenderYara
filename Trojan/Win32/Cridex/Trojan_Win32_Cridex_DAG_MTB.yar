
rule Trojan_Win32_Cridex_DAG_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DAG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 ff 2b c1 03 d8 8b 44 24 10 83 44 24 10 04 81 c5 40 1c 0f 01 ff 4c 24 14 89 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}