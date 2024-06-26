
rule Trojan_Win32_Qbot_SP_MTB{
	meta:
		description = "Trojan:Win32/Qbot.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 11 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 69 70 2d 61 64 72 65 73 73 2e 63 6f 6d } //01 00  http://www.ip-adress.com
		$a_81_1 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //01 00  SELECT * FROM Win32_OperatingSystem
		$a_81_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 6f 72 } //01 00  SELECT * FROM Win32_Processor
		$a_81_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00  SELECT * FROM AntiVirusProduct
		$a_81_4 = {4e 65 77 52 65 6d 6f 74 65 48 6f 73 74 } //01 00  NewRemoteHost
		$a_81_5 = {4e 65 77 45 78 74 65 72 6e 61 6c 50 6f 72 74 } //01 00  NewExternalPort
		$a_81_6 = {4e 65 77 50 72 6f 74 6f 63 6f 6c } //01 00  NewProtocol
		$a_81_7 = {4e 65 77 49 6e 74 65 72 6e 61 6c 50 6f 72 74 } //01 00  NewInternalPort
		$a_81_8 = {4e 65 77 49 6e 74 65 72 6e 61 6c 43 6c 69 65 6e 74 } //01 00  NewInternalClient
		$a_81_9 = {4e 65 77 45 6e 61 62 6c 65 64 } //01 00  NewEnabled
		$a_81_10 = {4e 65 77 4c 65 61 73 65 54 69 6d 65 } //01 00  NewLeaseTime
		$a_81_11 = {4e 65 77 44 65 73 63 72 69 70 74 69 6f 6e } //01 00  NewDescription
		$a_81_12 = {50 6f 72 74 4d 61 70 70 69 6e 67 45 6e 74 72 79 } //01 00  PortMappingEntry
		$a_81_13 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 73 70 } //01 00  \\.\pipe\%ssp
		$a_81_14 = {49 50 20 61 64 64 72 65 73 73 20 69 73 3a 20 3c 73 74 72 6f 6e 67 3e } //01 00  IP address is: <strong>
		$a_81_15 = {75 70 6e 70 3a 72 6f 6f 74 64 65 76 69 63 65 } //01 00  upnp:rootdevice
		$a_81_16 = {4d 2d 53 45 41 52 43 48 20 2a 20 48 54 54 50 2f 31 2e 31 } //00 00  M-SEARCH * HTTP/1.1
	condition:
		any of ($a_*)
 
}