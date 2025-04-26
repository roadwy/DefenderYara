
rule Trojan_BAT_Agensla_ABDX_MTB{
	meta:
		description = "Trojan:BAT/Agensla.ABDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 73 74 61 72 61 74 61 2e 65 78 65 } //1 astarata.exe
		$a_81_1 = {53 6f 6e 67 6f 66 74 68 65 6e 61 6d 65 } //1 Songofthename
		$a_81_2 = {24 33 64 30 37 39 37 39 30 2d 64 37 32 64 2d 34 34 62 37 2d 62 62 39 33 2d 39 33 32 65 66 39 64 38 35 39 39 62 } //1 $3d079790-d72d-44b7-bb93-932ef9d8599b
		$a_81_3 = {64 61 4e 61 6d 65 } //1 daName
		$a_81_4 = {54 72 79 43 61 6c 6c 4e 61 6d 65 } //1 TryCallName
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}