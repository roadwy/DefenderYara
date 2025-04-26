
rule Trojan_BAT_AgentTesla_NIE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0a 00 00 "
		
	strings :
		$a_01_0 = {46 72 6f 6d 42 61 73 65 36 34 } //10 FromBase64
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //10 GetMethod
		$a_01_2 = {23 66 61 73 76 78 66 61 66 64 66 64 73 67 64 66 67 64 66 66 73 64 66 66 66 61 66 67 73 64 64 64 64 64 6f 6b 75 69 6a 6f 75 69 6c 70 6f 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #fasvxfafdfdsgdfgdffsdfffafgsdddddokuijouilpoddddssaf.dll#
		$a_01_3 = {23 66 61 66 64 61 66 73 73 67 67 64 73 66 66 67 64 66 67 64 66 73 64 66 64 6b 67 63 66 69 6f 69 6f 61 61 61 61 61 6f 61 61 61 64 73 73 73 61 66 2e 64 6c 6c 23 } //1 #fafdafssggdsffgdfgdfsdfdkgcfioioaaaaaoaaadsssaf.dll#
		$a_01_4 = {23 69 6a 66 61 6b 6b 67 64 66 67 67 66 66 73 66 64 73 66 76 78 64 73 66 73 67 6b 2e 64 6c 6c 23 } //1 #ijfakkgdfggffsfdsfvxdsfsgk.dll#
		$a_01_5 = {23 73 66 67 64 73 2e 64 6c 6c 23 } //1 #sfgds.dll#
		$a_01_6 = {23 66 61 61 78 76 64 61 61 73 64 73 66 66 67 73 73 61 73 66 64 73 66 64 64 66 73 66 67 64 66 66 6b 6b 6c 76 63 6c 6a 69 67 66 64 64 64 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #faaxvdaasdsffgssasfdsfddfsfgdffkklvcljigfdddddddssaf.dll#
		$a_01_7 = {23 66 61 73 76 64 64 64 64 78 64 61 73 64 61 64 76 78 66 61 66 64 66 64 73 67 64 66 67 64 66 66 73 64 66 66 66 61 66 67 73 64 64 64 64 64 6f 6b 75 69 6a 6f 75 69 6c 70 6f 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //1 #fasvddddxdasdadvxfafdfdsgdfgdffsdfffafgsdddddokuijouilpoddddssaf.dll#
		$a_01_8 = {23 61 66 61 64 78 76 61 64 64 61 64 66 73 73 66 66 61 73 73 64 64 64 64 64 66 67 76 78 63 64 64 66 67 64 66 66 73 73 67 73 66 2e 64 6c 6c 23 } //1 #afadxvaddadfssffassdddddfgvxcddfgdffssgsf.dll#
		$a_01_9 = {6b 23 73 61 76 61 61 61 61 61 61 78 63 76 64 61 61 64 73 66 73 73 23 } //1 k#savaaaaaaxcvdaadsfss#
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=24
 
}