
rule Worm_Win32_Rebhip_I{
	meta:
		description = "Worm:Win32/Rebhip.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 6f 72 6c 6f 20 31 2e 39 2e 37 20 73 72 63 5c 57 69 6e 64 6f 77 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 57 69 6e 6c 6f 67 6f 6e 2e 70 64 62 } //4 borlo 1.9.7 src\WindowsApplication1\obj\Debug\Winlogon.pdb
	condition:
		((#a_01_0  & 1)*4) >=4
 
}