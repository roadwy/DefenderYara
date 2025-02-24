
rule Trojan_Win64_XDRKiller_DA_MTB{
	meta:
		description = "Trojan:Win64/XDRKiller.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 75 73 74 5f 78 64 72 5f 66 75 63 6b 65 72 2e 70 64 62 } //rust_xdr_fucker.pdb  10
		$a_80_1 = {5a 77 53 75 73 70 65 6e 64 50 72 6f 63 65 73 73 } //ZwSuspendProcess  1
		$a_80_2 = {33 36 30 53 61 66 65 2e 65 78 65 } //360Safe.exe  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}