
rule Trojan_BAT_LummaStealer_AAOE_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.AAOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 65 00 61 00 6d 00 41 00 50 00 49 00 5f 00 43 00 53 00 68 00 61 00 72 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  CreamAPI_CSharp.Properties.Resources
		$a_01_1 = {37 30 61 32 30 34 38 35 2d 61 33 36 66 2d 34 61 61 65 2d 62 66 33 34 2d 34 36 32 33 65 36 62 62 61 37 38 33 } //00 00  70a20485-a36f-4aae-bf34-4623e6bba783
	condition:
		any of ($a_*)
 
}