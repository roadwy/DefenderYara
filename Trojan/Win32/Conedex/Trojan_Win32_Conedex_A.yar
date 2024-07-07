
rule Trojan_Win32_Conedex_A{
	meta:
		description = "Trojan:Win32/Conedex.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 45 78 65 63 45 6e 64 28 69 64 2c 20 66 4f 6b 29 } //1 OnExecEnd(id, fOk)
		$a_01_1 = {3c 64 61 74 3e 3c 6a 73 74 3e } //1 <dat><jst>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}