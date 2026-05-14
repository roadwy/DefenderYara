
rule HackTool_BAT_CobaltStrike_EM_MTB{
	meta:
		description = "HackTool:BAT/CobaltStrike.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_81_0 = {75 70 6c 6f 61 64 20 62 65 61 63 6f 6e 2e 65 78 65 20 63 3a 5c 62 65 61 63 6f 6e 2e 65 78 65 } //2 upload beacon.exe c:\beacon.exe
		$a_81_1 = {5b 2b 5d 55 70 6c 6f 61 64 20 66 69 6c 65 20 64 6f 6e 65 21 } //2 [+]Upload file done!
		$a_81_2 = {77 6d 69 20 3d 20 5b 77 6d 69 63 6c 61 73 73 5d } //1 wmi = [wmiclass]
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1) >=5
 
}