
rule Trojan_Win32_NetWire_D_MTB{
	meta:
		description = "Trojan:Win32/NetWire.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {4c 4f 47 4f 4e 53 45 52 56 45 52 3d 5c } //1 LOGONSERVER=\
		$a_81_1 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4c 6f 67 73 5c } //1 AppData\Roaming\Logs\
		$a_81_2 = {43 4f 4d 50 55 54 45 52 4e 41 4d 45 3d } //1 COMPUTERNAME=
		$a_81_3 = {61 6d 61 72 69 63 65 6f 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 } //1 amariceo.duckdns.org
		$a_81_4 = {46 50 5f 4e 4f 5f 48 4f 53 54 5f 43 48 45 43 4b 3d } //1 FP_NO_HOST_CHECK=
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}