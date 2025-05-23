
rule Trojan_BAT_AgentTesla_AOK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AOK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_81_0 = {24 33 34 35 34 37 34 36 43 2d 44 44 45 45 2d 34 31 33 33 2d 39 38 45 44 2d 30 33 36 32 45 35 37 42 36 30 41 30 } //10 $3454746C-DDEE-4133-98ED-0362E57B60A0
		$a_81_1 = {24 35 35 65 63 31 61 65 38 2d 34 66 62 39 2d 34 34 64 61 2d 39 65 65 30 2d 38 35 39 34 66 63 64 31 36 62 34 35 } //10 $55ec1ae8-4fb9-44da-9ee0-8594fcd16b45
		$a_81_2 = {44 37 4a 34 38 48 37 37 46 39 59 35 35 4b 34 4a 43 41 47 35 46 44 } //1 D7J48H77F9Y55K4JCAG5FD
		$a_81_3 = {53 6d 61 72 74 46 6f 72 6d 61 74 2e 53 6d 61 72 74 45 78 74 65 6e 73 69 6f 6e 73 } //1 SmartFormat.SmartExtensions
		$a_81_4 = {4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 } //1 OffsetMarshaler
		$a_81_5 = {52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //1 ReturnMessage
		$a_81_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_7 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}