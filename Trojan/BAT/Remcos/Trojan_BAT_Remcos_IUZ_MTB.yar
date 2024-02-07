
rule Trojan_BAT_Remcos_IUZ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.IUZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 0a 00 "
		
	strings :
		$a_81_0 = {6b 6f 74 61 64 69 61 69 6e 63 2e 63 6f 6d } //0a 00  kotadiainc.com
		$a_81_1 = {70 68 69 6c 6f 78 2e 64 64 6e 73 2e 6e 65 74 } //01 00  philox.ddns.net
		$a_81_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_81_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_5 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}