
rule Trojan_BAT_Injector_ARR_MTB{
	meta:
		description = "Trojan:BAT/Injector.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 70 6e 70 20 3d 20 47 65 74 2d 50 6e 70 44 65 76 69 63 65 20 2d 49 6e 73 74 61 6e 63 65 49 64 20 28 22 50 43 49 5c 22 20 2b 20 24 70 63 69 53 68 6f 72 74 20 2b 20 22 2a 22 29 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //7 $pnp = Get-PnpDevice -InstanceId ("PCI\" + $pciShort + "*") -ErrorAction SilentlyContinue
		$a_81_1 = {2e 65 78 65 20 2f 46 20 22 24 74 61 72 67 65 74 22 20 2f 52 20 2f 44 20 59 20 32 3e 24 6e 75 6c 6c } //3 .exe /F "$target" /R /D Y 2>$null
		$a_81_2 = {77 68 69 6c 65 20 28 28 24 76 6d 2e 53 74 61 74 65 20 2d 6e 65 20 27 4f 66 66 27 29 20 2d 61 6e 64 20 28 24 77 61 69 74 65 64 20 2d 6c 74 20 24 6d 61 78 57 61 69 74 53 68 75 74 64 6f 77 6e 29 29 } //8 while (($vm.State -ne 'Off') -and ($waited -lt $maxWaitShutdown))
		$a_81_3 = {24 66 72 69 65 6e 64 6c 79 4e 61 6d 65 20 3d 20 69 66 20 28 24 70 6e 70 29 20 7b 20 24 70 6e 70 2e 46 72 69 65 6e 64 6c 79 4e 61 6d 65 20 7d 20 65 6c 73 65 20 7b 20 24 67 70 75 2e 4e 61 6d 65 20 7d } //4 $friendlyName = if ($pnp) { $pnp.FriendlyName } else { $gpu.Name }
		$a_81_4 = {57 72 69 74 65 2d 4c 6f 67 20 28 22 5b 24 28 24 56 4d 4e 61 6d 65 29 5d 20 43 6f 70 79 69 6e 67 20 24 28 24 53 6f 75 72 63 65 29 20 2d 3e 20 24 28 24 74 61 72 67 65 74 29 20 28 24 28 24 46 69 6c 65 4d 61 73 6b 29 29 22 29 } //6 Write-Log ("[$($VMName)] Copying $($Source) -> $($target) ($($FileMask))")
		$a_81_5 = {49 6e 6a 65 63 74 20 44 72 69 76 65 72 73 } //2 Inject Drivers
	condition:
		((#a_81_0  & 1)*7+(#a_81_1  & 1)*3+(#a_81_2  & 1)*8+(#a_81_3  & 1)*4+(#a_81_4  & 1)*6+(#a_81_5  & 1)*2) >=30
 
}