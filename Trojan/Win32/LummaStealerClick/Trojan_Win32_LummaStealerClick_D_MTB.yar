
rule Trojan_Win32_LummaStealerClick_D_MTB{
	meta:
		description = "Trojan:Win32/LummaStealerClick.D!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6f 00 2e 00 66 00 69 00 6c 00 65 00 5d 00 3a 00 3a 00 63 00 72 00 65 00 61 00 74 00 65 00 28 00 24 00 } //10 [system.io.file]::create($
		$a_00_1 = {68 00 74 00 74 00 70 00 } //10 http
		$a_00_2 = {24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //10 $env:computername
		$a_00_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 20 00 24 00 } //1 invoke-webrequest $
		$a_00_4 = {69 00 77 00 72 00 20 00 24 00 } //1 iwr $
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}