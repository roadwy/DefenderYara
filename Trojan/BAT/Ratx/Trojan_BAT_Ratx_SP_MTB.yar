
rule Trojan_BAT_Ratx_SP_MTB{
	meta:
		description = "Trojan:BAT/Ratx.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {47 69 61 75 54 4d 2e 43 53 68 61 72 70 2e 54 69 6b 69 52 6f 75 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 } //2 GiauTM.CSharp.TikiRouter.Properties
		$a_81_1 = {24 32 37 30 39 61 37 65 32 2d 64 35 35 35 2d 34 35 64 66 2d 61 30 66 61 2d 35 38 38 66 32 61 62 66 38 64 30 65 } //2 $2709a7e2-d555-45df-a0fa-588f2abf8d0e
		$a_81_2 = {52 6f 75 74 65 72 43 6f 6e 66 69 67 2e 74 73 76 } //1 RouterConfig.tsv
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}