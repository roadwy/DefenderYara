
rule Trojan_Win32_Conedex_C{
	meta:
		description = "Trojan:Win32/Conedex.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6e 61 76 69 67 61 74 65 28 64 6f 6d 61 69 6e 2b 27 3f 73 65 61 72 63 68 3d 27 20 2b } //1 navigate(domain+'?search=' +
		$a_01_1 = {3c 64 61 74 3e 3c 6a 73 74 3e } //1 <dat><jst>
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}