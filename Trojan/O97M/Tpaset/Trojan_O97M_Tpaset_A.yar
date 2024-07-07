
rule Trojan_O97M_Tpaset_A{
	meta:
		description = "Trojan:O97M/Tpaset.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {22 20 2d 4e 6f 50 20 2d 4e 6f 6e 49 20 2d 57 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 22 49 6e 76 6f 6b 65 2d 45 22 } //1 " -NoP -NonI -W Hidden -Command ""Invoke-E"
		$a_00_1 = {2b 20 22 78 70 72 65 73 73 69 6f 6e 20 24 28 4e 65 77 2d 4f 62 6a 65 63 74 20 49 4f 2e 53 74 72 65 61 6d 52 65 61 64 65 72 20 28 24 28 4e 65 77 2d 4f 62 22 } //1 + "xpression $(New-Object IO.StreamReader ($(New-Ob"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}