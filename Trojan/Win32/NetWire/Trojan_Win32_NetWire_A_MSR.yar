
rule Trojan_Win32_NetWire_A_MSR{
	meta:
		description = "Trojan:Win32/NetWire.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 85 c0 66 3d 1b 60 83 f6 00 85 c0 85 c0 85 c0 85 c0 83 f6 00 66 3d 33 51 85 c0 be [0-08] 83 f6 00 85 c0 66 3d 10 fb 66 3d bb 3f 66 3d a7 27 85 c0 83 f6 00 83 f6 00 66 3d 1c b3 83 f6 00 66 3d 94 70 66 3d 2d 09 81 c6 [0-08] 83 f6 00 83 f6 00 66 3d 8e 6c 85 c0 85 c0 83 f6 00 85 c0 83 f6 00 39 30 66 0f 6e fe 75 94 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}