
rule VirTool_Win32_SvcStealer_A_MTB{
	meta:
		description = "VirTool:Win32/SvcStealer.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 44 55 75 48 51 6f 47 45 30 6b 72 4b 77 38 56 47 67 34 47 46 7a 55 6b 43 78 6b 45 48 77 35 55 49 52 30 5a 4a 67 55 45 4d 54 4d 34 48 51 6f 5a 4b 45 6b 79 47 51 34 41 46 77 3d 3d } //1 GDUuHQoGE0krKw8VGg4GFzUkCxkEHw5UIR0ZJgUEMTM4HQoZKEkyGQ4AFw==
	condition:
		((#a_01_0  & 1)*1) >=1
 
}