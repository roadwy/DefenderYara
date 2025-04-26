
rule Trojan_Win32_Kechang_C_dha{
	meta:
		description = "Trojan:Win32/Kechang.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 4d 00 50 00 41 00 44 00 56 00 46 00 4e 00 2e 00 44 00 4c 00 4c 00 } //1 \MPADVFN.DLL
		$a_01_1 = {63 00 68 00 61 00 72 00 74 00 2e 00 68 00 65 00 61 00 6c 00 74 00 68 00 63 00 61 00 72 00 65 00 2d 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 68 00 74 00 6d 00 6c 00 } //2 chart.healthcare-internet.com/index.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=2
 
}