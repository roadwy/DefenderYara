
rule Trojan_BAT_Tedy_ARS_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6e 73 75 72 65 20 48 79 70 65 72 2d 56 20 68 79 70 65 72 76 69 73 6f 72 20 73 74 61 72 74 73 20 6f 6e 20 62 6f 6f 74 } //11 Ensure Hyper-V hypervisor starts on boot
		$a_81_1 = {49 6e 6a 65 63 74 20 51 52 65 73 2e 65 78 65 20 74 6f 20 56 4d } //9 Inject QRes.exe to VM
		$a_81_2 = {57 72 69 74 65 2d 4c 6f 67 20 22 41 75 74 6f 75 6e 61 74 74 65 6e 64 2e 78 6d 6c 20 69 6e 6a 65 63 74 65 64 20 69 6e 74 6f 20 50 61 6e 74 68 65 72 20 64 69 72 65 63 74 6f 72 79 22 } //6 Write-Log "Autounattend.xml injected into Panther directory"
		$a_81_3 = {49 6e 6a 65 63 74 20 75 6e 61 74 74 65 6e 64 2e 78 6d 6c 20 74 6f 20 72 6f 6f 74 20 66 6f 72 20 66 69 72 73 74 20 62 6f 6f 74 } //4 Inject unattend.xml to root for first boot
	condition:
		((#a_81_0  & 1)*11+(#a_81_1  & 1)*9+(#a_81_2  & 1)*6+(#a_81_3  & 1)*4) >=30
 
}