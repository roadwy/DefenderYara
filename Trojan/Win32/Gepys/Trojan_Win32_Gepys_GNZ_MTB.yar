
rule Trojan_Win32_Gepys_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Gepys.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 89 50 08 89 ca 81 f2 ?? ?? ?? ?? 85 c9 89 50 0c 8d 91 ?? ?? ?? ?? 8d 1c 12 0f 45 d3 89 50 54 8b 15 ?? ?? ?? ?? 8d 59 ff 89 5d f0 89 55 ec 8d 51 01 0f af 55 ec 89 50 50 31 d2 eb 1e 89 d6 89 d7 83 ce 01 0f af f1 29 f7 89 fe 8b 7d f0 21 d7 42 8a 9f ?? ?? ?? ?? 88 5c 30 10 3b 55 ec } //10
		$a_01_1 = {73 73 20 78 68 72 75 72 72 3e 3d } //1 ss xhrurr>=
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}