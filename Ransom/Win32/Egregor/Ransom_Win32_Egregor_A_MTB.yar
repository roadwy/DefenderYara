
rule Ransom_Win32_Egregor_A_MTB{
	meta:
		description = "Ransom:Win32/Egregor.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {25 47 72 65 65 74 69 6e 67 73 32 74 61 72 67 65 74 25 } //1 %Greetings2target%
		$a_81_1 = {25 65 67 72 65 67 6f 72 5f 64 61 74 61 25 } //1 %egregor_data%
		$a_81_2 = {2d 2d 45 47 52 45 47 4f 52 2d 2d } //1 --EGREGOR--
		$a_81_3 = {49 20 64 6f 20 6e 6f 74 20 66 65 61 72 20 79 6f 75 72 20 74 68 72 65 61 74 73 21 } //1 I do not fear your threats!
		$a_81_4 = {6d 73 66 74 65 73 71 6c 2e 65 78 65 3b 73 71 6c 61 67 65 6e 74 2e 65 78 65 3b 73 71 6c 62 72 6f 77 73 65 72 2e 65 78 65 3b 73 71 6c 77 72 69 74 65 72 2e 65 78 65 3b } //1 msftesql.exe;sqlagent.exe;sqlbrowser.exe;sqlwriter.exe;
		$a_81_5 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 77 61 73 20 41 54 54 41 43 4b 45 44 } //1 Your network was ATTACKED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}