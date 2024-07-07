
rule Trojan_Linux_Xorddos_A_xp{
	meta:
		description = "Trojan:Linux/Xorddos.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 65 74 63 2f 72 63 2e 64 2f 72 63 25 64 2e 64 2f 53 39 30 } //1 /etc/rc.d/rc%d.d/S90
		$a_00_1 = {73 65 64 20 2d 69 20 27 2f 5c 2f 65 74 63 5c 2f 63 72 6f 6e 2e } //1 sed -i '/\/etc\/cron.
		$a_00_2 = {c7 04 24 98 f9 0a 08 e8 fa 87 00 00 81 c4 2c 14 00 00 31 c0 } //1
		$a_00_3 = {2f 65 74 63 2f 63 72 6f 6e 2e 68 6f 75 72 6c 79 2f 67 63 63 2e 73 68 } //1 /etc/cron.hourly/gcc.sh
		$a_00_4 = {75 70 64 61 74 65 2d 72 63 2e 64 } //1 update-rc.d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}