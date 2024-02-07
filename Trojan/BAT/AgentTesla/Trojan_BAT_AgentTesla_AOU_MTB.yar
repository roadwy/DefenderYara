
rule Trojan_BAT_AgentTesla_AOU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 62 63 66 63 65 30 61 30 2d 65 63 31 37 2d 31 31 64 30 2d 38 64 31 30 2d 30 30 61 30 63 39 30 66 32 37 31 39 } //01 00  $bcfce0a0-ec17-11d0-8d10-00a0c90f2719
		$a_81_1 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_81_2 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_3 = {52 65 61 64 4f 6e 6c 79 44 69 63 74 69 6f 6e 61 72 79 } //01 00  ReadOnlyDictionary
		$a_81_4 = {4c 61 74 65 42 69 6e 64 69 6e 67 } //01 00  LateBinding
		$a_81_5 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //01 00  NewLateBinding
		$a_81_6 = {52 65 73 74 72 69 63 74 65 64 45 72 72 6f 72 } //01 00  RestrictedError
		$a_81_7 = {56 61 6c 75 65 45 6e 75 6d 65 72 61 74 6f 72 } //00 00  ValueEnumerator
	condition:
		any of ($a_*)
 
}