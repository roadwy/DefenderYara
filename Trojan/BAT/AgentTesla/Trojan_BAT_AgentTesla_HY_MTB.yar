
rule Trojan_BAT_AgentTesla_HY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 3d 22 57 69 6e 64 6f 77 73 20 48 6f 73 74 22 } //1 netsh advfirewall firewall delete rule name="Windows Host"
		$a_81_1 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 //cdn.discordapp.com/attachments/
		$a_81_2 = {76 69 72 75 73 74 6f 74 61 6c 75 70 6c 6f 61 64 32 } //1 virustotalupload2
		$a_81_3 = {74 61 73 6b 6d 67 72 } //1 taskmgr
		$a_81_4 = {70 65 72 66 6d 6f 6e } //1 perfmon
		$a_81_5 = {70 72 6f 63 65 73 73 20 65 78 70 6c 6f 72 65 72 } //1 process explorer
		$a_81_6 = {70 72 6f 63 65 73 73 20 68 61 63 6b 65 72 } //1 process hacker
		$a_81_7 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_81_8 = {50 53 52 65 61 64 4c 69 6e 65 } //1 PSReadLine
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}