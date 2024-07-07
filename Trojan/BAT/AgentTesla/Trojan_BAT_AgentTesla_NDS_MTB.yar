
rule Trojan_BAT_AgentTesla_NDS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {74 36 7a 63 67 36 68 62 70 61 62 65 67 72 70 73 75 66 38 64 68 33 62 64 39 68 34 67 66 33 73 76 } //1 t6zcg6hbpabegrpsuf8dh3bd9h4gf3sv
		$a_01_1 = {6c 31 31 69 49 49 6c 49 69 31 69 49 31 } //1 l11iIIlIi1iI1
		$a_01_2 = {79 67 6d 75 33 72 39 76 65 65 6a 77 6a 68 37 6a 61 32 70 70 32 6e 79 78 6b 39 32 37 73 75 79 6c } //1 ygmu3r9veejwjh7ja2pp2nyxk927suyl
		$a_01_3 = {69 69 6c 49 49 69 69 69 6c 69 49 6c } //1 iilIIiiiliIl
		$a_01_4 = {69 69 31 69 31 69 31 49 49 6c 6c 6c } //1 ii1i1i1IIlll
		$a_01_5 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_01_6 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_01_7 = {54 6f 57 69 6e 33 32 } //1 ToWin32
		$a_01_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}