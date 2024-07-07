
rule Trojan_BAT_AgentTesla_LAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 61 64 31 37 64 39 31 38 2d 65 66 65 62 2d 34 61 31 32 2d 62 37 65 63 2d 65 30 30 35 62 38 64 35 35 64 37 37 } //1 $ad17d918-efeb-4a12-b7ec-e005b8d55d77
		$a_01_1 = {57 69 6e 20 55 73 62 49 6e 69 74 } //1 Win UsbInit
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_7 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_8 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 } //1 SuspendLayout
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}