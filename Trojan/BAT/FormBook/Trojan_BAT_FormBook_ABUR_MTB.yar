
rule Trojan_BAT_FormBook_ABUR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 65 61 72 69 6e 67 5f 4d 61 63 68 69 6e 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //02 00  Bearing_Machine.Properties.Resources.resources
		$a_01_1 = {42 65 61 72 69 6e 67 5f 4d 61 63 68 69 6e 65 2e 53 79 73 74 65 6d 5f 4f 75 74 70 75 74 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Bearing_Machine.System_Output.resources
		$a_01_2 = {36 66 66 63 64 32 38 61 2d 64 35 34 65 2d 34 35 36 30 2d 62 39 32 38 2d 64 34 63 63 62 61 38 39 36 35 36 33 } //00 00  6ffcd28a-d54e-4560-b928-d4ccba896563
	condition:
		any of ($a_*)
 
}