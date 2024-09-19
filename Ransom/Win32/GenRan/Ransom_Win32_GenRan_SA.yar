
rule Ransom_Win32_GenRan_SA{
	meta:
		description = "Ransom:Win32/GenRan.SA,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-08] 2d 00 [0-04] 2d 00 [0-04] 2d 00 [0-04] 2d 00 [0-0c] 5c 00 [0-08] 2e 00 65 00 78 00 65 00 } //1
		$a_80_1 = {2d 2d 54 61 73 6b } //--Task  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}