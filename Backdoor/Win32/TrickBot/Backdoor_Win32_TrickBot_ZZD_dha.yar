
rule Backdoor_Win32_TrickBot_ZZD_dha{
	meta:
		description = "Backdoor:Win32/TrickBot.ZZD!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3c 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 3d 22 69 64 22 2f 3e 3c 6e 65 65 64 69 6e 66 6f 20 6e 61 6d 65 3d 22 69 70 22 2f 3e 3c 2f 6d 6f 64 75 6c 65 63 6f 6e 66 69 67 3e } //1 <moduleconfig><needinfo name="id"/><needinfo name="ip"/></moduleconfig>
	condition:
		((#a_01_0  & 1)*1) >=1
 
}