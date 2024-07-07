
rule Trojan_Linux_Melofee_B_MTB{
	meta:
		description = "Trojan:Linux/Melofee.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 73 62 69 6e 2f 72 6d 6d 6f 64 20 25 73 } //1 /sbin/rmmod %s
		$a_00_1 = {2f 73 62 69 6e 2f 69 6e 73 6d 6f 64 20 25 73 } //1 /sbin/insmod %s
		$a_00_2 = {72 6d 20 2d 66 72 20 2f 65 74 63 2f 72 63 2e 6d 6f 64 75 6c 65 73 } //1 rm -fr /etc/rc.modules
		$a_00_3 = {2f 65 74 63 2f 69 6e 74 65 6c 5f 61 75 64 69 6f 2f 61 75 64 69 6f 20 7c 20 78 61 72 67 73 20 6b 69 6c 6c 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c } //1 /etc/intel_audio/audio | xargs kill 2>/dev/null
		$a_03_4 = {55 48 89 e5 48 83 ec 30 48 89 7d e8 48 89 75 e0 89 55 dc 48 8b 45 e8 ba ed 01 00 00 be 41 02 00 00 48 89 c7 b8 00 00 00 00 e8 90 01 04 89 45 fc 83 7d fc 00 79 07 b8 ff ff ff ff eb 26 8b 45 dc 48 63 d0 48 8b 4d e0 8b 45 fc 48 89 ce 89 c7 e8 90 01 04 8b 45 fc 89 c7 e8 90 00 } //2
		$a_03_5 = {8b 45 a8 89 c2 48 8b 4d d8 8b 45 e4 48 89 ce 89 c7 e8 90 01 04 8b 45 e4 89 c7 e8 90 01 04 48 8d 45 a0 48 89 c7 e8 90 01 04 48 89 c2 48 8d 85 c0 f8 ff ff be b4 1e 40 00 48 89 c7 b8 00 00 00 00 e8 90 01 04 48 8d 85 c0 f8 ff ff 48 89 c7 e8 90 01 04 e8 90 01 04 89 45 e8 90 00 } //2
		$a_03_6 = {83 7d e8 00 75 90 01 01 c7 45 ec 03 00 00 00 eb 0e 8b 45 ec 89 c7 e8 90 01 04 83 45 ec 01 81 7d ec fe 00 00 00 0f 9e c0 84 c0 75 90 01 01 be 00 00 00 00 bf 4a 1d 40 00 e8 90 01 04 bf 01 00 00 00 e8 90 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*2) >=5
 
}