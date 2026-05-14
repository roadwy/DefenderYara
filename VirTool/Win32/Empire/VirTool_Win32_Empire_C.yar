
rule VirTool_Win32_Empire_C{
	meta:
		description = "VirTool:Win32/Empire.C,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {49 6e 76 6f 6b 65 2d 45 6d 70 69 72 65 20 2d 53 65 72 76 65 72 73 20 40 28 } //Invoke-Empire -Servers @(  1
		$a_80_1 = {2e 48 65 61 64 65 72 73 2e 41 64 64 28 22 55 73 65 72 2d 41 67 65 6e 74 22 } //.Headers.Add("User-Agent"  1
		$a_80_2 = {5b 47 43 5d 3a 3a 43 6f 6c 6c 65 63 74 28 29 } //[GC]::Collect()  1
		$a_80_3 = {28 70 73 7c 74 61 73 6b 6c 69 73 74 29 } //(ps|tasklist)  1
		$a_80_4 = {24 53 63 72 69 70 74 3a 43 6f 6e 74 72 6f 6c 53 65 72 76 65 72 73 5b 24 53 63 72 69 70 74 3a 53 65 72 76 65 72 49 6e 64 65 78 5d } //$Script:ControlServers[$Script:ServerIndex]  1
		$a_80_5 = {53 74 61 72 74 2d 4e 65 67 6f 74 69 61 74 65 20 2d 53 } //Start-Negotiate -S  1
		$a_80_6 = {20 2d 53 74 61 67 69 6e 67 4b 65 79 } // -StagingKey  1
		$a_80_7 = {24 73 63 72 69 70 74 3a 41 67 65 6e 74 4a 69 74 74 65 72 } //$script:AgentJitter  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}