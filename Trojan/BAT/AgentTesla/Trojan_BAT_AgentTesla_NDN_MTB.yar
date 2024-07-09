
rule Trojan_BAT_AgentTesla_NDN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 16 20 00 10 00 00 6f ?? ?? ?? 0a 0c 08 16 fe 02 13 05 11 05 2c 0a 06 11 04 16 08 6f ?? ?? ?? 0a 08 16 fe 02 13 06 11 06 2d d3 } //1
		$a_01_1 = {24 35 37 33 62 63 39 35 37 2d 38 35 30 31 2d 34 34 61 64 2d 36 35 34 34 2d 39 34 39 38 31 33 62 37 65 66 31 32 } //1 $573bc957-8501-44ad-6544-949813b7ef12
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}