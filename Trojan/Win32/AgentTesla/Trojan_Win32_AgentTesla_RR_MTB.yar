
rule Trojan_Win32_AgentTesla_RR_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4a 6f 68 6e 44 6f 65 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 44 69 6c 65 6d 6d 69 63 32 32 5c 66 6f 72 76 69 73 73 65 6e 64 65 73 5c 52 65 6f 76 69 } //1 JohnDoe\Application Data\Dilemmic22\forvissendes\Reovi
		$a_01_1 = {25 73 74 61 6e 64 61 72 64 62 65 74 69 6e 67 65 6c 73 65 73 25 5c 61 66 68 72 69 6e 67 73 5c 45 78 75 62 65 72 61 74 65 } //1 %standardbetingelses%\afhrings\Exuberate
		$a_01_2 = {44 69 66 66 65 72 65 6e 74 69 61 62 69 6c 69 74 65 74 73 6d 6e 67 64 65 72 73 5c 63 69 6e 6e 61 6d 6f 6d 75 6d 5c } //1 Differentiabilitetsmngders\cinnamomum\
		$a_01_3 = {48 6f 61 74 7a 69 6e 5c 64 72 69 66 74 73 72 61 61 64 73 } //1 Hoatzin\driftsraads
		$a_01_4 = {53 65 6e 64 65 74 69 64 65 72 6e 65 73 31 38 39 2e 6d 6f 72 } //1 Sendetidernes189.mor
		$a_01_5 = {53 6f 6c 62 61 74 74 65 72 69 65 72 73 2e 61 67 65 } //1 Solbatteriers.age
		$a_01_6 = {54 6f 70 61 72 74 69 73 79 73 74 65 6d 65 72 6e 65 73 2e 74 78 74 } //1 Topartisystemernes.txt
		$a_01_7 = {61 73 70 68 79 78 69 61 74 65 64 2e 67 72 69 } //1 asphyxiated.gri
		$a_01_8 = {62 6f 62 73 6c 65 64 2e 74 78 74 } //1 bobsled.txt
		$a_01_9 = {6f 76 65 72 65 6e 73 6b 6f 6d 73 74 6d 73 73 69 67 65 73 2e 72 75 6e } //1 overenskomstmssiges.run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}