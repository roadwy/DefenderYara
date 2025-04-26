
rule HackTool_Linux_WildFire_A_MTB{
	meta:
		description = "HackTool:Linux/WildFire.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 63 70 20 2f 74 6d 70 2f 70 61 6e 77 74 65 73 74 20 2f 75 73 72 2f 62 69 6e 2f 70 73 } //1 /bin/cp /tmp/panwtest /usr/bin/ps
		$a_01_1 = {53 61 6d 70 6c 65 20 45 78 65 63 75 74 65 64 20 53 75 63 63 65 73 73 66 75 6c 6c 79 2e } //1 Sample Executed Successfully.
		$a_03_2 = {41 57 41 89 ff 41 56 49 89 f6 41 55 49 89 d5 41 54 4c 8d 25 48 08 20 00 55 48 8d 2d 48 08 20 00 53 4c 29 e5 31 db 48 c1 fd 03 48 83 ec 08 e8 35 fe ff ff 48 85 ed 74 1e 0f 1f 84 ?? ?? ?? ?? ?? 4c 89 ea 4c 89 f6 44 89 ff 41 ff 14 dc 48 83 c3 01 48 39 eb 75 ea 48 83 c4 08 5b 5d 41 5c 41 5d 41 5e 41 5f c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}